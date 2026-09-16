rule TTP_XOR_WriteProcessMemory_bbce {
  strings:
    $key_bbce = { ec bc [2] de 9e [2] d8 ab [2] f6 ab [2] c9 b7 }

  condition:
    any of them
}