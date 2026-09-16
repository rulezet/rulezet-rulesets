rule TTP_XOR_WriteProcessMemory_fb9f {
  strings:
    $key_fb9f = { ac ed [2] 9e cf [2] 98 fa [2] b6 fa [2] 89 e6 }

  condition:
    any of them
}