rule TTP_XOR_QUAD_CurrentVersionRun_b1fd {
  strings:
    $key_b1fd = { e2 92 [2] c6 9c [2] ed b0 [2] c3 92 [2] d7 89 [2] d8 93 [2] c6 8e [2] c4 8f [2] df 89 [2] c3 8e [2] df a1 }

  condition:
    any of them
}