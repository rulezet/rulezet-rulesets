rule finspy_linux_installer1 {
  meta:
    description = "Rule for FinSpy Linux installer x86 or x64"
    author      = "Etienne Maynier, Amnesty Tech"
    sample      = "8aaf886a2a2cd459e65277343bc951a2d23555980eddd73218a5c608e6d2a29c"

  strings:
    $a = "%s/.kde/Autostart" ascii wide nocase
    $b = "%s/.kde4/Autostart" ascii wide nocase
    $c = "dmesg --notime 2>/dev/null | grep -i \"hypervisor detected\" | cut -d ':' -f2" ascii wide nocase
    $d = "g_plauncher" ascii wide nocase
    $e = "g_pinstall_host_location" ascii wide nocase
    $f = "g_pinstall_folder" ascii wide nocase
    $g = "%s/.bash_profile" ascii wide nocase
    $h = "lspci 2>/dev/null | grep -i \"system peripheral\" | grep -i \"virtual\"" ascii wide nocase
    $i = "lspci | grep -i \"system peripheral\" | grep -i \"virtual\"" ascii nocase

  condition:
    7 of them
}