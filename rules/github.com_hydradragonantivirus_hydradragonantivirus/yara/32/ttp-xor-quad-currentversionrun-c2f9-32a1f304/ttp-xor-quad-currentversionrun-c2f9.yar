rule TTP_XOR_QUAD_CurrentVersionRun_c2f9 {
  strings:
    $key_c2f9 = { 91 96 [2] b5 98 [2] 9e b4 [2] b0 96 [2] a4 8d [2] ab 97 [2] b5 8a [2] b7 8b [2] ac 8d [2] b0 8a [2] ac a5 }

  condition:
    any of them
}