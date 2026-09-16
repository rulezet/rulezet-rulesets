rule TTP_XOR_QUAD_CurrentVersionRun_c2fd {
  strings:
    $key_c2fd = { 91 92 [2] b5 9c [2] 9e b0 [2] b0 92 [2] a4 89 [2] ab 93 [2] b5 8e [2] b7 8f [2] ac 89 [2] b0 8e [2] ac a1 }

  condition:
    any of them
}