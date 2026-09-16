rule TTP_XOR_QUAD_CurrentVersionRun_d430 {
  strings:
    $key_d430 = { 87 5f [2] a3 51 [2] 88 7d [2] a6 5f [2] b2 44 [2] bd 5e [2] a3 43 [2] a1 42 [2] ba 44 [2] a6 43 [2] ba 6c }

  condition:
    any of them
}