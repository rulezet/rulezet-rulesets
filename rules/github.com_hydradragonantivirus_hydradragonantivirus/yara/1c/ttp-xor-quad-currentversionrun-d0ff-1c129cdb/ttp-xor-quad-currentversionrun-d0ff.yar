rule TTP_XOR_QUAD_CurrentVersionRun_d0ff {
  strings:
    $key_d0ff = { 83 90 [2] a7 9e [2] 8c b2 [2] a2 90 [2] b6 8b [2] b9 91 [2] a7 8c [2] a5 8d [2] be 8b [2] a2 8c [2] be a3 }

  condition:
    any of them
}