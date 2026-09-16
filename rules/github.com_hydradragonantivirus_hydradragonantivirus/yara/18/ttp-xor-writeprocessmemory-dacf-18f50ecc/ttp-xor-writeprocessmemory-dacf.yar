rule TTP_XOR_WriteProcessMemory_dacf {
  strings:
    $key_dacf = { 8d bd [2] bf 9f [2] b9 aa [2] 97 aa [2] a8 b6 }

  condition:
    any of them
}