rule TTP_XOR_WriteProcessMemory_1fd4 {
  strings:
    $key_1fd4 = { 48 a6 [2] 7a 84 [2] 7c b1 [2] 52 b1 [2] 6d ad }

  condition:
    any of them
}