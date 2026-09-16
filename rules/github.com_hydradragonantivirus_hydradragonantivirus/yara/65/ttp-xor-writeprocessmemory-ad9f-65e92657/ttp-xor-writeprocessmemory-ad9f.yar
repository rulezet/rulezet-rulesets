rule TTP_XOR_WriteProcessMemory_ad9f {
  strings:
    $key_ad9f = { fa ed [2] c8 cf [2] ce fa [2] e0 fa [2] df e6 }

  condition:
    any of them
}