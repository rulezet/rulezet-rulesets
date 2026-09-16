rule TTP_XOR_WriteProcessMemory_ac97 {
  strings:
    $key_ac97 = { fb e5 [2] c9 c7 [2] cf f2 [2] e1 f2 [2] de ee }

  condition:
    any of them
}