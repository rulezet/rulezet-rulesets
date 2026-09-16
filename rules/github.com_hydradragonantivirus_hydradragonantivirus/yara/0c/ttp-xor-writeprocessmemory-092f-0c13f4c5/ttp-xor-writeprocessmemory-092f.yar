rule TTP_XOR_WriteProcessMemory_092f {
  strings:
    $key_092f = { 5e 5d [2] 6c 7f [2] 6a 4a [2] 44 4a [2] 7b 56 }

  condition:
    any of them
}