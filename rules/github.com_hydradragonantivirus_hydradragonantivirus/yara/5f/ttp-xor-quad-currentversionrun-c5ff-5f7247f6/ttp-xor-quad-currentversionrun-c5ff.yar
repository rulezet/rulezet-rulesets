rule TTP_XOR_QUAD_CurrentVersionRun_c5ff {
  strings:
    $key_c5ff = { 96 90 [2] b2 9e [2] 99 b2 [2] b7 90 [2] a3 8b [2] ac 91 [2] b2 8c [2] b0 8d [2] ab 8b [2] b7 8c [2] ab a3 }

  condition:
    any of them
}