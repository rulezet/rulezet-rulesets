rule TTP_XOR_WriteProcessMemory_c943 {
  strings:
    $key_c943 = { 9e 31 [2] ac 13 [2] aa 26 [2] 84 26 [2] bb 3a }

  condition:
    any of them
}