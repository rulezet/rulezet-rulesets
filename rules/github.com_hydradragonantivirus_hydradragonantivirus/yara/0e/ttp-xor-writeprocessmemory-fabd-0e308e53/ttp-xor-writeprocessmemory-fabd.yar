rule TTP_XOR_WriteProcessMemory_fabd {
  strings:
    $key_fabd = { ad cf [2] 9f ed [2] 99 d8 [2] b7 d8 [2] 88 c4 }

  condition:
    any of them
}