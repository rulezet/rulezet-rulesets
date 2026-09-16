rule TTP_XOR_WriteProcessMemory_d1fd {
  strings:
    $key_d1fd = { 86 8f [2] b4 ad [2] b2 98 [2] 9c 98 [2] a3 84 }

  condition:
    any of them
}