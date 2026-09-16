rule TTP_XOR_QUAD_CurrentVersionRun_d70c {
  strings:
    $key_d70c = { 84 63 [2] a0 6d [2] 8b 41 [2] a5 63 [2] b1 78 [2] be 62 [2] a0 7f [2] a2 7e [2] b9 78 [2] a5 7f [2] b9 50 }

  condition:
    any of them
}