rule TTP_XOR_WriteProcessMemory_f9b6 {
  strings:
    $key_f9b6 = { ae c4 [2] 9c e6 [2] 9a d3 [2] b4 d3 [2] 8b cf }

  condition:
    any of them
}