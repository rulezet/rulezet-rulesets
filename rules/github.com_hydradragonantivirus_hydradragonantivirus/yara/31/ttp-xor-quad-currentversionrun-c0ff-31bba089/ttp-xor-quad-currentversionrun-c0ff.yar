rule TTP_XOR_QUAD_CurrentVersionRun_c0ff {
  strings:
    $key_c0ff = { 93 90 [2] b7 9e [2] 9c b2 [2] b2 90 [2] a6 8b [2] a9 91 [2] b7 8c [2] b5 8d [2] ae 8b [2] b2 8c [2] ae a3 }

  condition:
    any of them
}