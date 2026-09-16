rule DDoSManager {
  meta:
    copyright = "Intezer Labs"
    author    = "Intezer Labs"
    reference = "https://www.intezer.com"

  strings:
    $a0 = { 55 89 e5 5? 8b ?? 0c 8B ?? 08 85 ?? 7E 16 31 ?? 0F B6 ?? ?? 83 F? 19 83 C? 7A 88 ?? ?? 83 C? 01 }
    $b0 = "5CFake"
    $b1 = "/tmp/Cfg.9"
    $b2 = "0|%s|%s|1|65535|"
    $b3 = "8CManager"
    $b4 = "SingTool"

  condition:
    all of them
}