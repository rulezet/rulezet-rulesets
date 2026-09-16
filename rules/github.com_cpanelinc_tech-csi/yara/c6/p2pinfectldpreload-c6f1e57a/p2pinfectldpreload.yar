rule P2PinfectLDPreload {
  meta:
    author = "nbill@cadosecurity.com"
    description = "Detects P2Pinfect libs.so.1 payload"
  strings:
    $a1 = "env_var"
    $a2 = "main_file"
    $a3 = "hide.c"
    $b1 = "prefix"
    $b2 = "process1"
    $b3 = "process2"
    $b4 = "process3"
    $b5 = "owner"
    $c1 = "%d: [0-9A-Fa-f]:%X [0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu 2s"
    $c2 = "/proc/net/tcp"
    $c3 = "/proc/net/tcp6"
  condition:
    uint16(0) == 0x457f and (all of ($a*) or all of ($b*) or all of ($c*))
}