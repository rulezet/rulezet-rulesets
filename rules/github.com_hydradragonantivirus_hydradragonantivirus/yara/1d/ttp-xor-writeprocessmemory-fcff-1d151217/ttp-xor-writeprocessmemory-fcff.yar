rule TTP_XOR_WriteProcessMemory_fcff {
  strings:
    $key_fcff = { ab 8d [2] 99 af [2] 9f 9a [2] b1 9a [2] 8e 86 }

  condition:
    any of them
}