rule Win_Spyware_Banker_1350
{
strings:
	$a0 = { be48d2a3e39db68b9a164d2ac331c57d9cf977e87675ccbeecbd87c117ef78b56dbad46d5820cfc125dc1e4ef896db521b32d2cfe5aa92d16de21ef920ef33a5d98bdbcb }


condition:
	$a0
}