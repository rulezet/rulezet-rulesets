rule TTP_XOR_QUAD_CurrentVersionRun_cb9a {
  strings:
    $key_cb9a = { 98 f5 [2] bc fb [2] 97 d7 [2] b9 f5 [2] ad ee [2] a2 f4 [2] bc e9 [2] be e8 [2] a5 ee [2] b9 e9 [2] a5 c6 }

  condition:
    any of them
}