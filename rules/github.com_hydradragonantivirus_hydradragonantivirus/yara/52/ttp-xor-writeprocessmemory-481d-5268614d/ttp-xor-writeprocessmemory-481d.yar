rule TTP_XOR_WriteProcessMemory_481d {
  strings:
    $key_481d = { 1f 6f [2] 2d 4d [2] 2b 78 [2] 05 78 [2] 3a 64 }

  condition:
    any of them
}