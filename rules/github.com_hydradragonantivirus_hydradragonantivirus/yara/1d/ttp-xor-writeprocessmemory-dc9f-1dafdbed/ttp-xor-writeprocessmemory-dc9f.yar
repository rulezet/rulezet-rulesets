rule TTP_XOR_WriteProcessMemory_dc9f {
  strings:
    $key_dc9f = { 8b ed [2] b9 cf [2] bf fa [2] 91 fa [2] ae e6 }

  condition:
    any of them
}