import "pe"
rule _MPEG_movie_file_ {
  meta:
    description = "MPEG movie file"

  strings:
    $0 = { 00 00 01 BA 2F FF FD E6 C1 80 18 61 00 00 01 BB }

  condition:
    $0 at pe.entry_point
}