rule TTP_XOR_QUAD_CurrentVersionRun_d0fc {
  strings:
    $key_d0fc = { 83 93 [2] a7 9d [2] 8c b1 [2] a2 93 [2] b6 88 [2] b9 92 [2] a7 8f [2] a5 8e [2] be 88 [2] a2 8f [2] be a0 }

  condition:
    any of them
}