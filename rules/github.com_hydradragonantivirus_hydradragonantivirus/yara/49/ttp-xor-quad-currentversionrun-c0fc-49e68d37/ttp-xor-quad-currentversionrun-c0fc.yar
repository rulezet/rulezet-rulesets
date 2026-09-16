rule TTP_XOR_QUAD_CurrentVersionRun_c0fc {
  strings:
    $key_c0fc = { 93 93 [2] b7 9d [2] 9c b1 [2] b2 93 [2] a6 88 [2] a9 92 [2] b7 8f [2] b5 8e [2] ae 88 [2] b2 8f [2] ae a0 }

  condition:
    any of them
}