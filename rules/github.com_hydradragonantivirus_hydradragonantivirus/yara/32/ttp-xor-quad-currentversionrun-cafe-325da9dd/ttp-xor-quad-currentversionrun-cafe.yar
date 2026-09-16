rule TTP_XOR_QUAD_CurrentVersionRun_cafe {
  strings:
    $key_cafe = { 99 91 [2] bd 9f [2] 96 b3 [2] b8 91 [2] ac 8a [2] a3 90 [2] bd 8d [2] bf 8c [2] a4 8a [2] b8 8d [2] a4 a2 }

  condition:
    any of them
}