rule TTP_XOR_QUAD_CurrentVersionRun_dbfe {
  strings:
    $key_dbfe = { 88 91 [2] ac 9f [2] 87 b3 [2] a9 91 [2] bd 8a [2] b2 90 [2] ac 8d [2] ae 8c [2] b5 8a [2] a9 8d [2] b5 a2 }

  condition:
    any of them
}