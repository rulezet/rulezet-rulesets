rule TTP_XOR_WriteProcessMemory_9eb8 {
  strings:
    $key_9eb8 = { c9 ca [2] fb e8 [2] fd dd [2] d3 dd [2] ec c1 }

  condition:
    any of them
}