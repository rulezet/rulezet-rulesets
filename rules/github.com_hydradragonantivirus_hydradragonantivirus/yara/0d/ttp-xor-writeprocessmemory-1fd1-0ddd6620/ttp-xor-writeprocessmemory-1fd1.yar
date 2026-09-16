rule TTP_XOR_WriteProcessMemory_1fd1 {
  strings:
    $key_1fd1 = { 48 a3 [2] 7a 81 [2] 7c b4 [2] 52 b4 [2] 6d a8 }

  condition:
    any of them
}