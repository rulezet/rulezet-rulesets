rule TTP_XOR_WriteProcessMemory_fd4f {
  strings:
    $key_fd4f = { aa 3d [2] 98 1f [2] 9e 2a [2] b0 2a [2] 8f 36 }

  condition:
    any of them
}