rule Win_Adware_Virtumonde_15
{
strings:
	$a0 = { 94849abd27b81197c995a90fdfb2534bfa35c3e277f8effe087956b12dc4c577b41850a95cac4f8021b70fa84dd53c20b5f76d1638b6d928fd2423928ec8069233aa4e9bcbef046bbd19e00a3e6f4265 }


condition:
	$a0
}