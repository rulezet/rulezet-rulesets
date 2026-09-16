rule TTP_XOR_QUAD_CurrentVersionRun_dbe2 {
  strings:
    $key_dbe2 = { 88 8d [2] ac 83 [2] 87 af [2] a9 8d [2] bd 96 [2] b2 8c [2] ac 91 [2] ae 90 [2] b5 96 [2] a9 91 [2] b5 be }

  condition:
    any of them
}