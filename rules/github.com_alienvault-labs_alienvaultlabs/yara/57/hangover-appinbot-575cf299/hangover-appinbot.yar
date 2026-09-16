rule Hangover_Appinbot {
    strings:
        $a1 = "CreateToolhelp32Snapshot"
        $a2 = "Process32First"
        $a3 = "Process32Next"
        $a4 = "FIDR/"
        $a5 = "SUBSCRIBE %d"
        $a6 = "CLOSE %d"
        
    condition:
        all of them

}