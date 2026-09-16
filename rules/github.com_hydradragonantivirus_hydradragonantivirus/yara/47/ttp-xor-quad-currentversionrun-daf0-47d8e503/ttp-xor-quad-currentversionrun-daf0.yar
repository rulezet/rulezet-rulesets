rule TTP_XOR_QUAD_CurrentVersionRun_daf0 {
  strings:
    $key_daf0 = { 89 9f [2] ad 91 [2] 86 bd [2] a8 9f [2] bc 84 [2] b3 9e [2] ad 83 [2] af 82 [2] b4 84 [2] a8 83 [2] b4 ac }

  condition:
    any of them
}