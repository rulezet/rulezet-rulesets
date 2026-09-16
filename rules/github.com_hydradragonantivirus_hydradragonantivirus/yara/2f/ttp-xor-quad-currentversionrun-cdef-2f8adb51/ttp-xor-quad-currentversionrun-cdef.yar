rule TTP_XOR_QUAD_CurrentVersionRun_cdef {
  strings:
    $key_cdef = { 9e 80 [2] ba 8e [2] 91 a2 [2] bf 80 [2] ab 9b [2] a4 81 [2] ba 9c [2] b8 9d [2] a3 9b [2] bf 9c [2] a3 b3 }

  condition:
    any of them
}