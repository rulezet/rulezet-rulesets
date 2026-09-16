rule DLL_inject
{
    meta:
        Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
        Description = "Check for DLL Injection"
    strings:
        $var1 = "OpenProcess"
        $var2 = "VirtualAllocEx"
        $var3 = "LoadLibraryA"
        $var4 = "CreateFileA"
        $var5 = "WriteProcessMemory"
        $var6 = "HeapAlloc"
        $var7 = "GetProcAddress"
        $var8 = "CreateRemoteThread"
    condition:
        4 of them
}