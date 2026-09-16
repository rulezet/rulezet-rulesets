rule TTP_XOR_WriteProcessMemory_1fd6 {
  strings:
    $key_1fd6 = { 48 a4 [2] 7a 86 [2] 7c b3 [2] 52 b3 [2] 6d af }

  condition:
    any of them
}