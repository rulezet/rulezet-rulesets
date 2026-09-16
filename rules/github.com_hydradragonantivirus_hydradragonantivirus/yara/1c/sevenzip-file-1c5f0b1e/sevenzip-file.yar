rule sevenzip_file
{
  strings:
    $magic = { 37 7A BC AF 27 1C }
  condition:
    $magic at 0
}