rule TTP_XOR_WriteProcessMemory_ffbf {
  strings:
    $key_ffbf = { a8 cd [2] 9a ef [2] 9c da [2] b2 da [2] 8d c6 }

  condition:
    any of them
}