rule TTP_XOR_QUAD_CurrentVersionRun_c63c {
  strings:
    $key_c63c = { 95 53 [2] b1 5d [2] 9a 71 [2] b4 53 [2] a0 48 [2] af 52 [2] b1 4f [2] b3 4e [2] a8 48 [2] b4 4f [2] a8 60 }

  condition:
    any of them
}