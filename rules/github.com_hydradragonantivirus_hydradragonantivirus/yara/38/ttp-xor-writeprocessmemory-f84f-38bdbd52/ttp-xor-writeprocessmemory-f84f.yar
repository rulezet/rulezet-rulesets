rule TTP_XOR_WriteProcessMemory_f84f {
  strings:
    $key_f84f = { af 3d [2] 9d 1f [2] 9b 2a [2] b5 2a [2] 8a 36 }

  condition:
    any of them
}