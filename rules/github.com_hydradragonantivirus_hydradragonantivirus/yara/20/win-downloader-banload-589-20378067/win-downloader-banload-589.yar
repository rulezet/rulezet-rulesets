rule Win_Downloader_Banload_589
{
strings:
	$a0 = { 85d583e87363731b64a49fa45c5afee11cc115f42a69e0f56d454aa77022d8ceae1c646bd706d3cfc11f3bebce4e78d93b6b2f3f767fde2c64465bfedf79c9bf2253c81a }


condition:
	$a0
}