rule TTP_XOR_QUAD_CurrentVersionRun_c1fd {
  strings:
    $key_c1fd = { 92 92 [2] b6 9c [2] 9d b0 [2] b3 92 [2] a7 89 [2] a8 93 [2] b6 8e [2] b4 8f [2] af 89 [2] b3 8e [2] af a1 }

  condition:
    any of them
}