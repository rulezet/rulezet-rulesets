rule PEiD_01485_PDS_graphics_file_format_ {
  meta:
    description = "[PDS graphics file format]"
    ep_only     = "false"

  strings:
    $a = "IMAGEIDENTIFIER "

  condition:
    $a
}