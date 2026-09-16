rule TTP_XOR_QUAD_CurrentVersionRun_c2fe {
  strings:
    $key_c2fe = { 91 91 [2] b5 9f [2] 9e b3 [2] b0 91 [2] a4 8a [2] ab 90 [2] b5 8d [2] b7 8c [2] ac 8a [2] b0 8d [2] ac a2 }

  condition:
    any of them
}