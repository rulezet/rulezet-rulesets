rule TTP_XOR_QUAD_CurrentVersionRun_f1fd {
  strings:
    $key_f1fd = { a2 92 [2] 86 9c [2] ad b0 [2] 83 92 [2] 97 89 [2] 98 93 [2] 86 8e [2] 84 8f [2] 9f 89 [2] 83 8e [2] 9f a1 }

  condition:
    any of them
}