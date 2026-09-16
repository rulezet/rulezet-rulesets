rule TTP_XOR_WriteProcessMemory_5305 {
  strings:
    $key_5305 = { 04 77 [2] 36 55 [2] 30 60 [2] 1e 60 [2] 21 7c }

  condition:
    any of them
}