rule AdvancedInstaller: Caphyon {
  meta:
    author = "_pusher_"
    date   = "2016-07"

  strings:
    $a0 = "AI_SETUPEXEPATH" wide ascii nocase
    $a1 = "Advanced Installer" wide ascii nocase

  condition:
    $a0 and $a1
}