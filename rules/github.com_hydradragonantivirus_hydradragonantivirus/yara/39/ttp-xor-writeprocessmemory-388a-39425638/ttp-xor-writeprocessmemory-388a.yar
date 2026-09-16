rule TTP_XOR_WriteProcessMemory_388a {
  strings:
    $key_388a = { 6f f8 [2] 5d da [2] 5b ef [2] 75 ef [2] 4a f3 }

  condition:
    any of them
}